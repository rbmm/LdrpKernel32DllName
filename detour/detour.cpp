#include "StdAfx.h"
#include "LDasm.h"

_NT_BEGIN

#include "TRAMPOLINE.h"
#include "detour.h"

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

NTSTATUS NTAPI TrInit(PVOID ImageBase)
{
	ULONG op, size;
	if (PVOID pIAT = RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_IAT, &size))
	{
		SIZE_T ProtectSize = size;

		return ZwProtectVirtualMemory(NtCurrentProcess(), &pIAT, &ProtectSize, PAGE_READWRITE, &op);
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS NTAPI TrHook(PVOID pv, T_HOOK_ENTRY* entry)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	pv = TestJmp((PBYTE)pv);

	if (Z_DETOUR_TRAMPOLINE* pTramp = new (pv) Z_DETOUR_TRAMPOLINE(entry->hook))
	{
		if (pv = pTramp->Init(pv))
		{
			PVOID pThunk = *entry->pThunk;
			*entry->pThunk = pv;

			if (0 <= (status = pTramp->Set()))
			{
				//DbgPrint("%p[%p -> %p]\n", pTramp, pThunk, pv);
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
		entry->pTramp = 0;

		delete pTramp;
	}

	return STATUS_SUCCESS;
}

void NTAPI TrUnHook(_In_ T_HOOK_ENTRY* entry, _In_ ULONG n)
{
	do 
	{
		TrUnHook(entry++);
	} while (--n);
}

void NTAPI TrHook(_In_ T_HOOK_ENTRY* entry, _In_ ULONG n)
{
	do 
	{
		TrHook(*entry->pThunk, entry);
	} while (entry++, --n);
}

NTSTATUS NTAPI TrHook(_Inout_ void** p__imp, _In_ PVOID hook)
{
	T_HOOK_ENTRY entry = { p__imp, hook };
	return TrHook(*p__imp, &entry);
}

_NT_END