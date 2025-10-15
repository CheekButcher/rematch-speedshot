#include "ExportedInit.h"
#include <process.h> // _beginthreadex
#include <Windows.h>

// forward-declare the real functions in your rematch-speedshot code.
// Make sure these functions exist with compatible signatures.
extern unsigned int __stdcall MainThread(void* param);
extern void CleanupHooks();

// Helper to get HMODULE for this DLL by address.
static HMODULE GetThisModuleHandle()
{
    HMODULE hMod = NULL;
    BOOL ok = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&GetThisModuleHandle),
        &hMod);
    if (!ok) {
        hMod = GetModuleHandleW(L"rematch-speedshot.dll");
    }
    return hMod;
}

__declspec(dllexport) void WINAPI RematchSpeedshot_Init(void)
{
    HMODULE hMod = GetThisModuleHandle();
    if (!hMod) return;

    // Start your existing MainThread on a new thread to avoid doing heavy work in DllMain
    uintptr_t th = _beginthreadex(nullptr, 0, MainThread, (void*)hMod, 0, nullptr);
    if (th) CloseHandle((HANDLE)th);
}

__declspec(dllexport) void WINAPI RematchSpeedshot_Shutdown(void)
{
    // call the cleanup routine that already exists
    CleanupHooks();
}
