#include "stdafx.h"

_NT_BEGIN

#include "..\detour\detour.h"
#include "inject.h"

EXTERN_C PVOID __imp_CreateProcessInternalW = 0;

#ifdef _M_IX86 
#pragma comment(linker, "/alternatename:__imp__CreateProcessInternalW@48=___imp_CreateProcessInternalW")
#endif

BOOL
WINAPI
hook_CreateProcessInternalW (
							 _In_opt_ HANDLE hToken,
							 _In_opt_ PCWSTR lpApplicationName,
							 _Inout_opt_ PWSTR lpCommandLine,
							 _In_opt_ PSECURITY_ATTRIBUTES lpProcessAttributes,
							 _In_opt_ PSECURITY_ATTRIBUTES lpThreadAttributes,
							 _In_ BOOL bInheritHandles,
							 _In_ DWORD dwCreationFlags,
							 _In_opt_ PVOID lpEnvironment,
							 _In_opt_ PCWSTR lpCurrentDirectory,
							 _In_ STARTUPINFOW* lpStartupInfo,
							 _Out_ PPROCESS_INFORMATION lpProcessInformation,
							 _Out_opt_ PHANDLE phNewToken
							 )
{
	HRESULT hr = E_OUTOFMEMORY;

	if (PWSTR psz = new WCHAR[MINSHORT])
	{
		if (GetModuleFileNameW((HMODULE)&__ImageBase, psz, MINSHORT))
		{
			if (PWSTR pc = wcsrchr(psz, '\\'))
			{
				*pc = 0;
				DLL_INFO di { psz, 15591 };

				hr = di.CreateProcessWithDll(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
					bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, phNewToken);
			}
		}
		else
		{
			hr = GetLastError();
		}
		delete [] psz;
	}

	SetLastError(hr);

	return hr == NOERROR;
}

void WINAPI OnApc(PVOID status, PVOID, PVOID)
{
	PWSTR psz;

	if (FormatMessageW(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE, 
		GetModuleHandle(L"ntdll"), (ULONG)(ULONG_PTR)status, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (PWSTR)&psz, 0, 0))
	{
		ULONG id = GetCurrentProcessId();
		WCHAR sz[64];
		swprintf_s(sz, _countof(sz), L"Demo from %x(%u)", id, id);
		MessageBoxW(0, psz, sz, MB_ICONINFORMATION);
		LocalFree(psz);
	}
}

#include "..\inc\initterm.h"

PVOID GetCreateAddr()
{
	HMODULE hmod;
	PVOID pv;

	const static char aCreateProcessInternalW[] = "CreateProcessInternalW";
	
	if (hmod = GetModuleHandleW(L"kernelbase.dll"))
	{
		if (pv = GetProcAddress(hmod, aCreateProcessInternalW))
		{
			return pv;
		}
	}

	if (hmod = GetModuleHandleW(L"kernel32.dll"))
	{
		if (pv = GetProcAddress(hmod, aCreateProcessInternalW))
		{
			return pv;
		}
	}

	return 0;
}

HRESULT DoInit()
{
	initterm();

	NTSTATUS status = TrInit();

	if (0 <= status)
	{
		T_HOOK_ENTRY entry = { 0, hook_CreateProcessInternalW, &__imp_CreateProcessInternalW };

		if (PVOID pv = GetCreateAddr())
		{
			status = TrHook(pv, &entry);
		}
		else
		{
			status = RtlGetLastNtStatus();
		}
	}

	ZwQueueApcThread(NtCurrentThread(), OnApc, (PVOID)(ULONG_PTR)status, 0, 0);

	return S_OK;
}

STDAPI DllRegisterServer()
{
	MessageBoxW(0, GetCommandLineW(), L"Start", MB_ICONINFORMATION);

	if (__imp_CreateProcessInternalW = GetCreateAddr())
	{
		WCHAR comspec[MAX_PATH];
		if (GetEnvironmentVariableW(L"comspec", comspec, _countof(comspec)))
		{
			STARTUPINFOW si = { sizeof(si) };
			PROCESS_INFORMATION pi;
			if (hook_CreateProcessInternalW(0, comspec, 0, 0, 0, 0, 0, 0, 0, &si, &pi, 0))
			{
				NtClose(pi.hThread);
				NtClose(pi.hProcess);
			}
		}
	}
	return S_OK;
}

_NT_END