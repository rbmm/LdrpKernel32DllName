#include "../inc/StdAfx.h"

#pragma intrinsic(memcpy,strcmp,wcslen)

_NT_BEGIN

#include "../inc/nobase.h"
//#define _PRINT_CPP_NAMES_
#include "../inc/asmfunc.h"

PCWSTR __cdecl wkernel32()ASM_FUNCTION;

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
	CPP_FUNCTION;

	if (PVOID hmod = get_hmod(0))
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
						RtlInitUnicodeString(&kernel32, wkernel32());

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

NTSTATUS InitBootstrapI(HANDLE hProcess, PVOID* ppKernel32, PCWSTR pszBootstrapDll, ULONG cb)
{
	CPP_FUNCTION;

	UNICODE_STRING str;

	RtlInitUnicodeString(&str, pszBootstrapDll);

	PVOID Buffer = 0;
	SIZE_T s = cb;
	NTSTATUS status = NtAllocateVirtualMemory(hProcess, &Buffer, 0, &s, MEM_COMMIT, PAGE_READWRITE);

	if (0 <= status)
	{
		if (0 <= (status = NtWriteVirtualMemory(hProcess, Buffer, const_cast<PWSTR>(pszBootstrapDll), cb, 0)))
		{
			ULONG op;
			PVOID pKernel32 = *ppKernel32, BaseAddress = pKernel32;
			str.Buffer = (PWSTR)Buffer;

			if (0 <= (status = NtProtectVirtualMemory(hProcess, &BaseAddress, &(s = sizeof(UNICODE_STRING)), PAGE_READWRITE, &op)))
			{
				status = NtWriteVirtualMemory(hProcess, pKernel32, &str, sizeof(UNICODE_STRING), 0);
				NtProtectVirtualMemory(hProcess, &BaseAddress, &s, op, &op);
			}
		}

		if (0 > status)
		{
			NtFreeVirtualMemory(hProcess, (void**)&Buffer, &(s = 0), MEM_RELEASE);
		}
	}

	return status;
}

_NT_END