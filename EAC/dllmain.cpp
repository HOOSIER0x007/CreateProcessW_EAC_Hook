// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "misc_utils.hpp"
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

bool inject_image(const wchar_t* window_class_name, const wchar_t* image_short_name)
{
    printf("[~] entering %s\n", __FUNCTION__);

    printf("[~] waiting for game to open...\n");

    const auto game_window = impl::wait_on_object([window_class_name]() { return FindWindowW(window_class_name, nullptr); });

    if (!game_window)
    {
        printf("[!] timed out\n");
        return false;
    }

    const auto window_thread = GetWindowThreadProcessId(game_window, nullptr);

    if (!window_thread)
    {
        printf("GetWindowThreadProcessId fail\n");
        return false;
    }

    printf("[~] window thread found [0x%lx]\n", window_thread);

    // since w10 1607, the limit for maximum path isn't actually MAX_PATH, just assume it is.
    auto dll_path = std::make_unique<wchar_t[]>(MAX_PATH);
    GetFullPathNameW(image_short_name, MAX_PATH, dll_path.get(), nullptr);

    const auto loaded_module = LoadLibraryW(dll_path.get());

    if (!loaded_module)
    {
        printf("LoadLibraryW fail\n");
        return false;
    }

    printf("[~] loaded module to local process [0x%p]\n", loaded_module);

    const auto window_hook = GetProcAddress(loaded_module, "wnd_hk");

    if (!window_hook)
    {
        printf("[!] can't find needed export in implanted dll, last error: 0x%lx", GetLastError());
        return false;
    }

    printf("[~] posting message...\n");

    // spam the fuck out of the message handler
    for (auto i = 0; i < 50; i++)
        PostThreadMessageW(window_thread, 0x5b0, 0, 0);

    printf("[~] dll implanted\n");

    printf("[~] leaving %s\n", __FUNCTION__);

    return true;
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
    
    inject_image(L"UnityWndClass", L"C:\\rust_sdk.dll");

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