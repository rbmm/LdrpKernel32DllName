#include "stdafx.h"

#ifndef _WIN64
#error 
#endif

_NT_BEGIN

#include "inject.h"

ULONG GetSectionSize(PIMAGE_SECTION_HEADER pish)
{
	if ((pish->Characteristics & (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE)) == IMAGE_SCN_MEM_READ)
	{
		ULONG VirtualSize = pish->Misc.VirtualSize, SizeOfRawData = pish->SizeOfRawData;

		return SizeOfRawData < VirtualSize ? SizeOfRawData : VirtualSize;
	}

	return 0;
}

PVOID FindLdrpKernel32DllName(_In_ PVOID hmod, _Out_ PULONG_PTR pBuffer, _Inout_ PULONG_PTR TransferAddress = 0)
{
	union {
		PIMAGE_NT_HEADERS pinth;
		PIMAGE_NT_HEADERS32 pinth32;
		PIMAGE_NT_HEADERS64 pinth64;
	};

	if (pinth = RtlImageNtHeader(hmod))
	{
		ULONG algn, n;
		ULONG_PTR ImageBase, AddressOfEntryPoint;

		switch (pinth->OptionalHeader.Magic)
		{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			ImageBase = pinth32->OptionalHeader.ImageBase;
			AddressOfEntryPoint = pinth32->OptionalHeader.AddressOfEntryPoint;
			algn = __alignof(UNICODE_STRING32);
			n = sizeof(UNICODE_STRING64);
			break;
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			ImageBase = pinth64->OptionalHeader.ImageBase;
			AddressOfEntryPoint = pinth64->OptionalHeader.AddressOfEntryPoint;
			algn = __alignof(UNICODE_STRING64);
			n = sizeof(UNICODE_STRING64);
			break;
		default: return 0;
		}

		LONG_PTR Delta = (ULONG_PTR)hmod - ImageBase;

		if (TransferAddress)
		{
			*TransferAddress -= (ULONG_PTR)hmod + AddressOfEntryPoint;
		}

		if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
		{
			PVOID pstr = 0;

			PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);
			do 
			{
				ULONG VirtualSize = GetSectionSize(pish);

				if (VirtualSize > n)
				{
					n = 1 + (VirtualSize - n) / algn;

					union {
						PVOID pv;
						PUNICODE_STRING str;
						PUNICODE_STRING64 str64;
						PUNICODE_STRING32 str32;
						ULONG_PTR up;
					};

					PVOID VirtualAddress = RtlOffsetToPointer(hmod, pish->VirtualAddress);
					pv = VirtualAddress;

					STATIC_UNICODE_STRING(kernel32, "kernel32.dll");
					do 
					{
						if (str->Length == kernel32.Length &&
							str->MaximumLength == kernel32.MaximumLength)
						{
							ULONG_PTR Buffer = algn == __alignof(UNICODE_STRING) ? str64->Buffer : 
								str32->Buffer;

							if (!(Buffer & (__alignof(WCHAR) - 1)))
							{
								Buffer += Delta;

								if (Buffer - (ULONG_PTR)VirtualAddress < VirtualSize)
								{
									if (!_wcsicmp((PWSTR)Buffer, kernel32.Buffer))
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
					} while (up += algn, --n);
				}

			} while (pish++, --NumberOfSections);

			return pstr;
		}
	}

	return 0;
}

static const WCHAR KnownDlls32_ntdll[] = L"\\KnownDlls32\\ntdll.dll";

PVOID FindLdrpKernel32DllName(_Out_ PULONG_PTR pBuffer)
{
	if (HMODULE hmod = GetModuleHandle(KnownDlls32_ntdll + _countof("\\KnownDlls32")))
	{
		return FindLdrpKernel32DllName(hmod, pBuffer);
	}

	return 0;
}

NTSTATUS GetTransferAddress(HANDLE hSection, void** TransferAddress)
{
	SECTION_IMAGE_INFORMATION sii;
	NTSTATUS status = ZwQuerySection(hSection, SectionImageInformation, &sii, sizeof(sii), 0);
	if (0 <= status)
	{
		if (sii.TransferAddress)
		{
			*TransferAddress = sii.TransferAddress;

			return STATUS_SUCCESS;
		}

		return STATUS_SECTION_NOT_IMAGE; 
	}

	return status;
}

PVOID FindLdrpKernel32DllNameWow64(_Out_ PULONG_PTR pBuffer)
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, KnownDlls32_ntdll);
	HANDLE hSection;

	NTSTATUS status = ZwOpenSection(&hSection, SECTION_MAP_EXECUTE|SECTION_QUERY, &oa);

	if (0 <= status)
	{
		PVOID BaseAddress = 0, TransferAddress;
		SIZE_T ViewSize = 0;

		0 <= (status = GetTransferAddress(hSection, &TransferAddress)) &&
			0 <= (status = ZwMapViewOfSection(hSection, NtCurrentProcess(), 
			&BaseAddress, 0, 0, 0, &ViewSize, ViewUnmap, 0/*MEM_DIFFERENT_IMAGE_BASE_OK*/, PAGE_EXECUTE));

		NtClose(hSection);

		if (0 <= status)
		{
			status = STATUS_PROCEDURE_NOT_FOUND;

			PVOID pKernel32DllName = FindLdrpKernel32DllName(BaseAddress, pBuffer, (PULONG_PTR)&TransferAddress);

			ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);

			if (pKernel32DllName)
			{
				*pBuffer += (ULONG_PTR)TransferAddress;

				return (PVOID)((ULONG_PTR)pKernel32DllName + (ULONG_PTR)TransferAddress);
			}

			return 0;
		}
	}

	return 0;
}

NTSTATUS InitBootstrapI(HANDLE hProcess, 
						PVOID pKernel32, 
						PCWSTR pszBootstrapDll, 
						ULONG cb, 
						PVOID bWow)
{
	union {
		UNICODE_STRING str;
		UNICODE_STRING32 str32;
		UNICODE_STRING64 str64;
	};

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
			if (bWow)
			{
				str32.Buffer = (ULONG)(ULONG_PTR)Buffer;
				cb = sizeof(UNICODE_STRING32);
			}
			else
			{
				str64.Buffer = (ULONG_PTR)Buffer;
				cb = sizeof(UNICODE_STRING64);
			}

			if (0 <= (status = ZwProtectVirtualMemory(hProcess, &BaseAddress, &(s = cb), PAGE_READWRITE, &op)))
			{
				status = ZwWriteVirtualMemory(hProcess, pKernel32, &str, cb, 0);
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

	ULONG u = bWow ? 32 : 64;

	NTSTATUS status = STATUS_INTERNAL_ERROR;

	int len = 0;
	PWSTR buf = 0;

	while (0 < (len = _snwprintf(buf, len, L"%s\\LdrpKernel%u.dll%c%I64X*%s\\Payload%u.dll%c%x", psz, u, 0, Str, psz, u, 0, Ordinal)))
	{
		if (buf)
		{
			status = InitBootstrapI(hProcess, pKernel32, buf, len * sizeof(WCHAR), bWow);
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
	static PVOID pKernel32_32 = 0, pKernel32_64 = 0;
	static ULONG_PTR pBuf32 = 0, pBuf64 = 0;

	HRESULT hr = ERROR_INTERNAL_ERROR;

	PVOID pstr;
	ULONG_PTR buf;

	if (!pKernel32_64)
	{
		if (pstr = FindLdrpKernel32DllName(&buf))
		{
			pKernel32_64 = pstr, pBuf64 = buf;
		}
		else
		{
			return HRESULT_FROM_NT(STATUS_UNSUCCESSFUL);
		}
	}

	if (!pKernel32_32)
	{
		if (pstr = FindLdrpKernel32DllNameWow64(&buf))
		{
			pKernel32_32 = pstr, pBuf32 = buf;
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

	while (0 < (len = _snwprintf(lpNewCommandLine, len, L"%p*%p*%s", pKernel32_32, pKernel32_64, lpCommandLine)))
	{
		if (lpNewCommandLine)
		{
			if (CreateProcessInternalW(hToken, lpApplicationName, lpNewCommandLine, 
				lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
				dwCreationFlags|CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, phNewToken))
			{
				PVOID wow;

				if (0 > (hr = NtQueryInformationProcess(lpProcessInformation->hProcess, ProcessWow64Information, &wow, sizeof(wow), 0)) ||
					0 > (hr = InitBootstrap(lpProcessInformation->hProcess, wow ? pKernel32_32 : pKernel32_64, wow ? pBuf32 : pBuf64, wow)) ||
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