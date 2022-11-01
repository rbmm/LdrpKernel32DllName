#define SECURITY_WIN32
#include "../inc/stdafx.h"

_NT_BEGIN

EXTERN_C
WINBASEAPI
NTSTATUS
FASTCALL
K32BaseThreadInitThunk(
					   BOOL bInitializeTermsrv, 
					   LPTHREAD_START_ROUTINE lpStartAddress, 
					   PVOID lpParameter
					   );

EXTERN_C PVOID __imp_K32BaseThreadInitThunk = 0;

#ifdef _M_IX86 
#pragma comment(linker, "/alternatename:__imp_@K32BaseThreadInitThunk@12=___imp_K32BaseThreadInitThunk")
#endif

void TermsrvGetWindowsDirectoryW()
{
	__debugbreak();
}

void LoadMainDll(PWSTR Buffer)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us, Buffer);

	if (ULONG ordinal = wcstoul(Buffer + wcslen(Buffer) + 1, &Buffer, 16))
	{
		if (!*Buffer && ordinal < MAXUSHORT)
		{
			HMODULE hmod;

			if (0 <= LdrLoadDll(0, 0, &us, &hmod))
			{
				FARPROC fp;
				if (0 > LdrGetProcedureAddress(hmod, 0, ordinal, (void**)&fp) || fp())
				{
					LdrUnloadDll(hmod);
				}
			}
		}
	}
}

void RevertLdrpKernel32DllName(PUNICODE_STRING pKernel32DllName)
{
	PWSTR Buffer = pKernel32DllName->Buffer;

	PWSTR kernel32 = (PWSTR)(ULONG_PTR)_wcstoui64(Buffer + wcslen(Buffer) + 1, &Buffer, 16);

	if (*Buffer == '*')
	{
		LoadMainDll(Buffer + 1);

		PVOID BaseAddress = pKernel32DllName;
		SIZE_T s = sizeof(UNICODE_STRING), r;
		ULONG op;
		if (0 <= ZwProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &s, PAGE_READWRITE, &op))
		{
			ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&pKernel32DllName->Buffer, &(r = 0), MEM_RELEASE);
			RtlInitUnicodeString(pKernel32DllName, kernel32);
			ZwProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &s, op, &op);
		}
	}
}

NTSTATUS 
FASTCALL 
BaseThreadInitThunk(
					BOOL bInitializeTermsrv, 
					LPTHREAD_START_ROUTINE lpStartAddress, 
					PVOID lpParameter
					)
{
	union {
		PVOID func;
		HMODULE hmod;
	};

	if (!__imp_K32BaseThreadInitThunk)
	{
		static HMODULE shmod = 0;
		
		NTSTATUS status;

		if (!shmod)
		{
			STATIC_UNICODE_STRING_(kernel32);
			if (0 > (status = LdrGetDllHandle(0, 0, &kernel32, &hmod)))
			{
				return status;
			}
			shmod = hmod;
		}

		STATIC_ANSI_STRING(aBaseThreadInitThunk, "BaseThreadInitThunk");

		if (0 > (status = LdrGetProcedureAddress(shmod, &aBaseThreadInitThunk, 0, &func)))
		{
			return status;
		}

		__imp_K32BaseThreadInitThunk = func;
	}

	if (bInitializeTermsrv)
	{
		PUNICODE_STRING CommandLine = &RtlGetCurrentPeb()->ProcessParameters->CommandLine;
		if (PWSTR Buffer = CommandLine->Buffer)
		{

#ifndef _WIN64
			ULONG_PTR pKernel32DllNameWow = (ULONG_PTR)
#endif
				_wcstoui64(Buffer, &Buffer, 16);
			
			if (*Buffer == '*')
			{

#ifdef _WIN64
				ULONG_PTR pKernel32DllName = (ULONG_PTR)
#endif
					_wcstoui64(Buffer + 1, &Buffer, 16);
				
				if (*Buffer == '*')
				{
					RtlInitUnicodeString(CommandLine, Buffer + 1);
						
					RevertLdrpKernel32DllName((PUNICODE_STRING)
#ifdef _WIN64
						pKernel32DllName
#else
						pKernel32DllNameWow
#endif
						);
				}
			}
		}
	}

	return K32BaseThreadInitThunk(bInitializeTermsrv, lpStartAddress, lpParameter);
}

_NT_END