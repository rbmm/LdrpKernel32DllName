#include "stdafx.h"

#ifdef _WIN64
#error 
#endif

_NT_BEGIN

#include "inject.h"

//#define _PRINT_CPP_NAMES_
#include "../inc/asmfunc.h"

ULONG64 FASTCALL FindLdrpKernel3264DllName(PULONG64 pBuf64)ASM_FUNCTION;

NTSTATUS FASTCALL InitBootstrapI64(HANDLE hProcess,
								   PVOID ppKernel32,
								   PCWSTR pszBootstrapDll, 
								   ULONG cb)ASM_FUNCTION;

ULONG GetSectionSize(PIMAGE_SECTION_HEADER pish)
{
	if ((pish->Characteristics & (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE)) == IMAGE_SCN_MEM_READ)
	{
		ULONG VirtualSize = pish->Misc.VirtualSize, SizeOfRawData = pish->SizeOfRawData;

		return SizeOfRawData < VirtualSize ? SizeOfRawData : VirtualSize;
	}

	return 0;
}

PVOID FindLdrpKernel32DllName(_Out_ PULONG_PTR pBuffer)
{
	if (PVOID hmod = GetModuleHandleW(L"ntdll"))
	{
		if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(hmod))
		{
			if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
			{
				PVOID pstr = 0;

				PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);
				do 
				{
					ULONG VirtualSize = GetSectionSize(pish);

					if (VirtualSize > sizeof(UNICODE_STRING))
					{
						ULONG n = 1 + (VirtualSize - sizeof(UNICODE_STRING)) / __alignof(UNICODE_STRING);

						union {
							PVOID pv;
							PUNICODE_STRING str;
							ULONG_PTR up;
						};

						PVOID VirtualAddress = RtlOffsetToPointer(hmod, pish->VirtualAddress);
						pv = VirtualAddress;

						UNICODE_STRING kernel32;
						RtlInitUnicodeString(&kernel32, L"kernel32.dll");

						do 
						{
							if (str->Length == kernel32.Length &&
								str->MaximumLength == kernel32.MaximumLength)
							{
								ULONG_PTR Buffer = (ULONG_PTR)str->Buffer;

								if (!(Buffer & (__alignof(WCHAR) - 1)))
								{
									if (Buffer - (ULONG_PTR)VirtualAddress < VirtualSize)
									{
										if (RtlEqualUnicodeString(str, &kernel32, TRUE))
										{
											if (pstr)
											{
												return 0;
											}

											pstr = pv, *pBuffer = Buffer;
										}
									}
								}
							}
						} while (up += __alignof(UNICODE_STRING), --n);
					}

				} while (pish++, --NumberOfSections);

				return pstr;
			}
		}
	}

	return 0;
}

BOOL bWowInit = FALSE;
PVOID gWow;

NTSTATUS FASTCALL InitBootstrapI(HANDLE hProcess, PVOID pKernel32, PCWSTR pszBootstrapDll, ULONG cb)
{
	UNICODE_STRING str;

	RtlInitUnicodeString(&str, pszBootstrapDll);

	PVOID Buffer = 0;
	SIZE_T s = cb;
	NTSTATUS status = ZwAllocateVirtualMemory(hProcess, &Buffer, 0, &s, MEM_COMMIT, PAGE_READWRITE);

	if (0 <= status)
	{
		if (0 <= (status = ZwWriteVirtualMemory(hProcess, Buffer, const_cast<PWSTR>(pszBootstrapDll), cb, 0)))
		{
			ULONG op;
			PVOID BaseAddress = pKernel32;
			str.Buffer = (PWSTR)Buffer;

			if (0 <= (status = ZwProtectVirtualMemory(hProcess, &BaseAddress, &(s = sizeof(UNICODE_STRING)), PAGE_READWRITE, &op)))
			{
				status = ZwWriteVirtualMemory(hProcess, pKernel32, &str, sizeof(UNICODE_STRING), 0);
				ZwProtectVirtualMemory(hProcess, &BaseAddress, &s, op, &op);
			}
		}

		if (0 > status)
		{
			ZwFreeVirtualMemory(hProcess, (void**)&Buffer, &(s = 0), MEM_RELEASE);
		}
	}

	return status;
}

HRESULT DLL_INFO::InitBootstrap(HANDLE hProcess, PVOID pKernel32, ULONG64 Str, PVOID bWow)
{
	PCWSTR psz = lpPathName;

	ULONG u = !bWow && gWow ? 64 : 32;

	NTSTATUS status = STATUS_INTERNAL_ERROR;

	int len = 0;
	PWSTR buf = 0;

	while (0 < (len = _snwprintf(buf, len, L"%s\\LdrpKernel%u.dll%c%I64X*%s\\Payload%u.dll%c%x", psz, u, 0, Str, psz, u, 0, Ordinal)))
	{
		if (buf)
		{
			status = (gWow && !bWow ? InitBootstrapI64 : InitBootstrapI)(hProcess, pKernel32, buf, len * sizeof(WCHAR));
			break;
		}

		++len;
		if (!(buf = (PWSTR)_malloca(len * sizeof(WCHAR))))
		{
			status = STATUS_NO_MEMORY;
			break;
		}
	}

	if (buf)
	{
		_freea(buf);
	}

	return status ? HRESULT_FROM_NT(status) : S_OK;
}

HRESULT
DLL_INFO::CreateProcessWithDll(
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
							   )
{
	static PVOID pKernel32_32 = 0;
	static ULONG64 pKernel32_64 = 0;
	static ULONG_PTR pBuf32 = 0;
	static ULONG64 pBuf64 = 0;

	HRESULT hr = ERROR_INTERNAL_ERROR;

	if (!pKernel32_32)
	{
		ULONG_PTR buf;
		if (PVOID pstr = FindLdrpKernel32DllName(&buf))
		{
			pKernel32_32 = pstr, pBuf32 = buf;
		}
		else
		{
			return HRESULT_FROM_NT(STATUS_UNSUCCESSFUL);
		}
	}

	if (!bWowInit)
	{
		if (0 > (hr = NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information, &gWow, sizeof(gWow), 0)))
		{
			return HRESULT_FROM_NT(hr);
		}

		bWowInit = TRUE;
	}

	if (!pKernel32_64 && gWow)
	{
		ULONG64 buf;
		if (ULONG64 pstr = FindLdrpKernel3264DllName(&buf))
		{
			pKernel32_64 = pstr, pBuf64 = buf;
		}
		else
		{
			return HRESULT_FROM_NT(STATUS_UNSUCCESSFUL);
		}
	}

	if (!lpCommandLine)
	{
		lpCommandLine = L"";
	}

	hr = ERROR_INTERNAL_ERROR;

	int len = 0;
	PWSTR lpNewCommandLine = 0;

	while (0 < (len = _snwprintf(lpNewCommandLine, len, L"%p*%I64X*%s", pKernel32_32, pKernel32_64, lpCommandLine)))
	{
		if (lpNewCommandLine)
		{
			if (CreateProcessInternalW(hToken, lpApplicationName, lpNewCommandLine, 
				lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
				dwCreationFlags|CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, phNewToken))
			{
				PVOID wow;

				if (0 > (hr = NtQueryInformationProcess(lpProcessInformation->hProcess, ProcessWow64Information, &wow, sizeof(wow), 0)) ||
					0 > (hr = InitBootstrap(lpProcessInformation->hProcess, wow ? pKernel32_32 : &pKernel32_64, wow ? pBuf32 : pBuf64, wow)) ||
					NOERROR != BOOL_TO_ERROR(dwCreationFlags & CREATE_SUSPENDED ? TRUE : ResumeThread(lpProcessInformation->hThread)))
				{
					TerminateProcess(lpProcessInformation->hProcess, 0);
					NtClose(lpProcessInformation->hThread);
					NtClose(lpProcessInformation->hProcess);
				}
			}
			else
			{
				hr = GetLastError();
			}
			break;
		}

		if (len >= MAXSHORT)
		{
			hr = RPC_S_STRING_TOO_LONG;
			break;
		}

		++len;
		if (!(lpNewCommandLine = (PWSTR)_malloca(len * sizeof(WCHAR))))
		{
			hr = E_OUTOFMEMORY;
			break;
		}
	}

	if (lpNewCommandLine)
	{
		_freea(lpNewCommandLine);
	}

	return HRESULT_FROM_WIN32(hr);
}

_NT_END