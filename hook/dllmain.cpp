// dllmain.cpp : Defines the entry point for the DLL application.

#include "pch.h"
#include "detours.h"
#include "Api.h"

static BOOL InstallHook(LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction)
{
	HMODULE module = GetModuleHandleA(dll);
	*originalFunction = (LPVOID)GetProcAddress(module, function);

	if (*originalFunction)
	{
		DetourAttach(originalFunction, hookedFunction);
		return true;
	}
	return false;
}


void mainhook() {
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
    LoadConfigInformation();
	InstallHook("Shell32.dll", "SHGetIDListFromObject", (LPVOID*)& TrueSHGetIDListFromObject, HookSHGetIDListFromObject);
	InstallHook("ntdll.dll", "NtQueryDirectoryFile", (LPVOID*)& Real_NtQueryDirectoryFile, Hooked_NtQueryDirectoryFile);

	DetourTransactionCommit();
}

HHOOK hHook = NULL;
HINSTANCE hInstance = NULL;

// Hook procedure for WH_GETMESSAGE
LRESULT CALLBACK GetMsgProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && lParam != 0) {
        MSG* pMsg = (MSG*)lParam;

        // Check for specific messages in the Explorer process
        if (pMsg->message == WM_SETTEXT || pMsg->message == WM_COMMAND || pMsg->message == WM_GETTEXT) {
            TCHAR className[256];
            HWND hwnd = pMsg->hwnd;

            GetClassName(hwnd, className, sizeof(className) / sizeof(TCHAR));
            OutputDebugString(className);
            if (_tcscmp(className, _T("SearchEditBox")) == 0) {
                OutputDebugString(_T("Search box interaction detected!\n"));
                // Additional logic can go here
            }
        }
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		mainhook();
        hInstance = hModule;
       // hHook = SetWindowsHookEx(WH_CALLWNDPROC, GetMsgProc, hInstance, 0);
        if (hHook == NULL) {
            OutputDebugString(_T("Failed to set hook!\n"));
        }
        else {
            OutputDebugString(_T("Hook set successfully!\n"));
        }
		CreateThread(NULL, 0, CreatePipe, NULL, 0, NULL);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        if (hHook) {
            UnhookWindowsHookEx(hHook);
            hHook = NULL;
        }
        break;
    }
    return TRUE;
}

