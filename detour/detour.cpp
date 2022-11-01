#include "StdAfx.h"
#include "LDasm.h"

_NT_BEGIN

#include "TRAMPOLINE.h"
#include "detour.h"

static volatile UCHAR guz;

PVOID MyGetProcedureAddress(PVOID ImageBase, PCSTR lpsz, ULONG Ordinal, int nLoops = 4)
{
	PVOID stack = alloca(guz);
	UNICODE_STRING DllName = {};

__loop:

	ULONG Size;

	if (PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)
		RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &Size))
	{
		if (Ordinal)
		{
			// convert Ordinal to index in AddressOfFunctions[]

			if ((Ordinal -= pied->Base) < pied->NumberOfFunctions)
			{
__index:
				PSTR pfn = RtlOffsetToPointer(ImageBase, ((PDWORD)RtlOffsetToPointer(ImageBase, pied->AddressOfFunctions))[Ordinal]);

				if ((ULONG_PTR)pfn - (ULONG_PTR)pied >= Size)
				{
					return pfn;
				}

				// forwarded export

				if (nLoops--)
				{
					if (lpsz = strrchr(pfn, '.'))
					{
						ULONG BytesInUnicodeString, BytesInMultiByteString = RtlPointerToOffset(pfn, lpsz);

						if (0 <= RtlMultiByteToUnicodeSize(&BytesInUnicodeString, pfn, BytesInMultiByteString) && BytesInUnicodeString < MAXUSHORT)
						{
							if (DllName.MaximumLength < BytesInUnicodeString)
							{
								DllName.MaximumLength = (USHORT)RtlPointerToOffset(
									DllName.Buffer = (PWSTR)alloca(BytesInUnicodeString - DllName.MaximumLength), stack);
							}

							if (0 <= RtlMultiByteToUnicodeN(DllName.Buffer, DllName.MaximumLength, &BytesInUnicodeString, pfn, BytesInMultiByteString))
							{
								DllName.Length = (USHORT)BytesInUnicodeString;

								HMODULE hmod;

								if (0 <= LdrGetDllHandle(0, 0, &DllName, &hmod))
								{
									ImageBase = hmod;

									if (*++lpsz == '#')
									{
										if ((Ordinal = strtoul(lpsz + 1, (char**)&lpsz, 10)) && !*lpsz)
										{
											lpsz = 0;
											goto __loop;
										}
									}
									else
									{
										Ordinal = 0;
										goto __loop;
									}
								}
							}
						}
					}
				}
			}
		}
		else
		{
			DWORD a = 0, b = pied->NumberOfNames;

			if (b)
			{
				PDWORD AddressOfNames = (PDWORD)RtlOffsetToPointer(ImageBase, pied->AddressOfNames);
				do
				{
					Ordinal = (a + b) >> 1;

					int i = strcmp(lpsz, RtlOffsetToPointer(ImageBase, AddressOfNames[Ordinal]));

					if (!i)
					{
						// this is index in AddressOfFunctions[]
						Ordinal = ((PWORD)RtlOffsetToPointer(ImageBase, pied->AddressOfNameOrdinals))[Ordinal];
						goto __index;
					}

					if (0 > i) b = Ordinal; else a = Ordinal + 1;

				} while (a < b);
			}
		}
	}

	return 0;
}

PVOID TestJmp(PBYTE pv)
{
__loop:
	ldasm_data ld;
	BYTE len = ldasm( pv, &ld, is_x64 );

	if (((ld.flags & (F_INVALID|F_DISP|F_MODRM|F_IMM)) == (F_DISP|F_MODRM)) &&
		ld.disp_size == 4 && ld.modrm == 0x25 && ld.opcd_size == 1 && 
		pv[ld.opcd_offset] == 0xff)
	{
#if defined(_M_IX86)
		void** ppv = *(void***)(pv + ld.disp_offset);
#elif defined (_M_X64)
		void** ppv = (void**)(pv + len + (LONG_PTR)*(LONG*)(pv + ld.disp_offset));
#else
#error
#endif

		if (!((ULONG_PTR)ppv & (sizeof(PVOID) - 1)))
		{
			pv = (PBYTE)*ppv;
			goto __loop;
		}
	}

	return pv;
}

BOOLEAN IsWindows_8_1_OrGreater;

NTSTATUS NTAPI TrInit(PVOID ImageBase)
{
	ULONG dwMajorVersion, dwMinorVersion;
	RtlGetNtVersionNumbers(&dwMajorVersion, &dwMinorVersion, 0);
	IsWindows_8_1_OrGreater = _WIN32_WINNT_WINBLUE <= ((dwMajorVersion << 8)| dwMinorVersion);

	ULONG op, size;
	if (PVOID pIAT = RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_IAT, &size))
	{
		SIZE_T ProtectSize = size;

		return ZwProtectVirtualMemory(NtCurrentProcess(), &pIAT, &ProtectSize, PAGE_READWRITE, &op);
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS NTAPI TrUnHook(T_HOOK_ENTRY* entry)
{
	if (Z_DETOUR_TRAMPOLINE* pTramp = entry->pTramp)
	{
		NTSTATUS status = pTramp->Remove();

		if (0 > status)
		{
			return status;
		}

		*entry->pThunk = entry->hook;
		entry->hook = pTramp->pvDetour;

		delete pTramp;
	}

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI TrHook(HMODULE hmod, T_HOOK_ENTRY* entry)
{
	PCSTR funcName = entry->funcName;

	ANSI_STRING as, *pas = 0;
	ULONG Ordinal =  0;

	if (IS_INTRESOURCE(funcName))
	{
		Ordinal = (ULONG)(ULONG_PTR)funcName;
	}
	else
	{
		RtlInitAnsiString(pas = &as, funcName);
	}

	DbgPrint("TrHook: (#%u, %s)\r\n", Ordinal, Ordinal ? "" : funcName);

	PVOID pv;
	NTSTATUS status;

	if (IsWindows_8_1_OrGreater)
	{
		if (0 > (status = LdrGetProcedureAddress(hmod, pas, Ordinal, &pv)))
		{
			return status;
		}
	}
	else
	{
		if (!(pv = MyGetProcedureAddress(hmod, funcName, Ordinal)))
		{
			return STATUS_PROCEDURE_NOT_FOUND;
		}
	}

	return TrHook(pv, entry);
}

NTSTATUS NTAPI TrHook(PVOID pv, T_HOOK_ENTRY* entry, _In_opt_ BOOLEAN bProtect/* = TRUE*/)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	pv = TestJmp((PBYTE)pv);

	if (Z_DETOUR_TRAMPOLINE* pTramp = new (pv) Z_DETOUR_TRAMPOLINE(entry->hook))
	{
		if (pv = pTramp->Init(pv))
		{
			PVOID pThunk = *entry->pThunk;
			*entry->pThunk = pv;

			if (0 <= (status = pTramp->Set(bProtect)))
			{
				DbgPrint("%p[%p -> %p]\n", pTramp, pThunk, pv);
				entry->hook = pThunk;
				entry->pTramp = pTramp;
				return STATUS_SUCCESS;
			}

			*entry->pThunk = pThunk;
		}
		delete pTramp;
	}

	return status;
}

void NTAPI TrUnHook(TR_HOOK_DLL* pphDLL[])
{
	while (TR_HOOK_DLL* phDLL = *pphDLL++)
	{
		T_HOOK_ENTRY* entry = phDLL->hookV;

		while (entry->funcName)
		{
			TrUnHook(entry++);
		}
	}
}

void NTAPI TrHook(PVOID hmod, PCUNICODE_STRING DllName, TR_HOOK_DLL* pphDLL[])
{
	while (TR_HOOK_DLL* phDLL = *pphDLL++)
	{
		UNICODE_STRING Name;
		RtlInitUnicodeString(&Name, phDLL->lpcszDllName);

		if (RtlEqualUnicodeString(DllName, &Name, TRUE))
		{
			T_HOOK_ENTRY* entry = phDLL->hookV;

			while (entry->hook)
			{
				TrHook((HMODULE)hmod, entry++);
			}

			break;
		}
	}
}

void NTAPI TrHook(PCUNICODE_STRING DllName, TR_HOOK_DLL* pphDLL[])
{
	HMODULE hmod;
	if (0 <= LdrGetDllHandle(0, 0, DllName, &hmod))
	{
		TrHook(hmod, DllName, pphDLL);
	}
}

void NTAPI TrHook(TR_HOOK_DLL* pphDLL[])
{
	while (TR_HOOK_DLL* phDLL = *pphDLL++)
	{
		UNICODE_STRING Name;
		RtlInitUnicodeString(&Name, phDLL->lpcszDllName);

		HMODULE hmod;

		if (0 <= LdrGetDllHandle(0, 0, &Name, &hmod))
		{
			T_HOOK_ENTRY* entry = phDLL->hookV;

			while (entry->hook)
			{
				TrHook(hmod, entry++);
			}
		}
	}
}

_NT_END