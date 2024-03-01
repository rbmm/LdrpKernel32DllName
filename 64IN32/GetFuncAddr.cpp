#define WIN32_LEAN_AND_MEAN
#include "../inc/StdAfx.h"

_NT_BEGIN
#include "../inc/nobase.h"

//#define _PRINT_CPP_NAMES_
#include "../inc/asmfunc.h"

PIMAGE_DOS_HEADER GetNtBase()
{
	return (PIMAGE_DOS_HEADER)CONTAINING_RECORD(
		reinterpret_cast<_TEB*>(NtCurrentTeb())->ProcessEnvironmentBlock->Ldr->InInitializationOrderModuleList.Flink,
		_LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks)->DllBase;
}

PVOID __fastcall GetFuncAddress(PCSTR lpsz)
{
	CPP_FUNCTION;

	PIMAGE_DOS_HEADER pidh = GetNtBase();

	PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(pidh, pidh->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(pidh, 
		pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD AddressOfNames = (PDWORD)RtlOffsetToPointer(pidh, pied->AddressOfNames);
	PDWORD AddressOfFunctions = (PDWORD)RtlOffsetToPointer(pidh, pied->AddressOfFunctions);
	PWORD AddressOfNameOrdinals = (PWORD)RtlOffsetToPointer(pidh, pied->AddressOfNameOrdinals);

	DWORD a = 0, b, o;

	if (b = pied->NumberOfNames) 
	{
		do
		{
			int i = strcmp(lpsz, RtlOffsetToPointer(pidh, AddressOfNames[o = (a + b) >> 1]));
			if (!i)
			{
				PVOID pv = RtlOffsetToPointer(pidh, AddressOfFunctions[AddressOfNameOrdinals[o]]);

				if ((ULONG_PTR)pv - (ULONG_PTR)pied < pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
				{
					__debugbreak();
					return 0;
				}

				return pv;
			}

			if (0 > i) b = o; else a = o + 1;

		} while (a < b);
	}

	__debugbreak();
	return 0;
}

_NT_END
