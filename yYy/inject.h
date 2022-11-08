#pragma once

// this api not declared in windows headers, declare it here
EXTERN_C
WINBASEAPI
BOOL
WINAPI
CreateProcessInternalW (
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
						);

struct DLL_INFO 
{
	PCWSTR lpPathName;
	ULONG Ordinal;

	HRESULT InitBootstrap(HANDLE hProcess, PVOID pKernel32, ULONG64 Str, PVOID bWow);

	HRESULT CreateProcessWithDll(
		_In_opt_ HANDLE hToken,
		_In_opt_ PCWSTR lpApplicationName,
		_In_opt_ PCWSTR lpCommandLine,
		_In_opt_ PSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_ PSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ BOOL bInheritHandles,
		_In_ DWORD dwCreationFlags,
		_In_opt_ PVOID lpEnvironment,
		_In_opt_ PCWSTR lpCurrentDirectory,
		_In_ STARTUPINFOW* lpStartupInfo,
		_Out_ PPROCESS_INFORMATION lpProcessInformation,
		_Out_opt_ PHANDLE phNewToken
		);
};
