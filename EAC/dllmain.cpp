// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <MinHook.h>
#include <string>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <thread>
#include <chrono>
#include <filesystem>
#include <memory>
#include <stdint.h>
#include <string_view>

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64-v141-mtd.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86-v141-mtd.lib")
#endif 

HANDLE hGAME = NULL;
TCHAR szEXEName[MAX_PATH];

typedef BOOL(WINAPI* hCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
hCreateProcessW tCreateProcessW = NULL;

BOOL WINAPI rCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    BOOL status = tCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    printf("lpApplicationName: %s\n", std::wstring(lpApplicationName));
    printf("PID %i\n", GetProcessId(lpProcessInformation->hProcess));

    if (std::wstring(lpApplicationName).find(L"D") != std::wstring::npos) {
        hGAME = lpProcessInformation->hProcess;

        printf("Found game in rCreateProcessW\n");
        for (;;) {
            Sleep(1000);
        }
    }

    return status;
}

wchar_t dllPath[] = TEXT("C:\\rust_sdk.dll");

DWORD WINAPI mainthread(LPVOID) {
    MH_Initialize();
    MH_CreateHook(CreateProcessW, (LPVOID)&rCreateProcessW, (LPVOID*)&tCreateProcessW);
    MH_EnableHook(CreateProcessW);
    while (hGAME == NULL) {
        Sleep(250);
    }

    printf("Found game in mainthread\n");
    
    long GameBase = NULL;
        
    LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (addr == NULL) {
        printf("Error: the LoadLibraryA function was not found inside kernel32.dll library.\n");
    }
    LPVOID arg = (LPVOID)VirtualAllocEx(hGAME, NULL, sizeof(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (arg == NULL) {
        printf("Error: the memory could not be allocated inside the chosen process.\n");
    }
    /*
    * Write the argument to LoadLibraryA to the process's newly allocated memory region.
    */
    int n = WriteProcessMemory(hGAME, arg, dllPath, sizeof(dllPath), NULL);
    if (n == 0) {
        printf("Error: there was no bytes written to the process's address space.\n");
    }
    /*
    * Inject our DLL into the process's address space.
    */
    HANDLE threadID = CreateRemoteThread(hGAME, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, NULL);
    if (threadID == NULL) {
        printf("Error: the remote thread could not be created.\n");
    }
    else {
        printf("Success: the remote thread was successfully created.\n");
    }
        
    printf("Done press enter\n");
    getchar();

    CloseHandle(hGAME);

    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD REASON, LPVOID) {
    if (REASON == DLL_PROCESS_ATTACH) {
        AllocConsole();
        FILE* F = NULL;
        freopen_s(&F, "CONOUT$", "w", stdout);
        CreateThread(NULL, NULL, mainthread, NULL, NULL, NULL);
    }
    return TRUE;
}