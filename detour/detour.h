#pragma once

struct T_HOOK_ENTRY 
{
	void** pThunk;
	PVOID hook;
	union Z_DETOUR_TRAMPOLINE* pTramp;
};

NTSTATUS NTAPI TrInit(PVOID ImageBase = &__ImageBase);

void NTAPI TrHook(_In_ T_HOOK_ENTRY* entry, _In_ ULONG n);
void NTAPI TrUnHook(_In_ T_HOOK_ENTRY* entry, _In_ ULONG n);

NTSTATUS NTAPI TrHook(_Inout_ void** p__imp, _In_ PVOID hook);

#define _DECLARE_T_HOOK(pfn) EXTERN_C extern PVOID __imp_ ## pfn;

#define DECLARE_T_HOOK_X86(pfn, n) _DECLARE_T_HOOK(pfn) __pragma(comment(linker, _CRT_STRINGIZE(/alternatename:___imp_##pfn##=__imp__##pfn##@##n)))

#ifdef _M_IX86
#define DECLARE_T_HOOK(pfn, n) DECLARE_T_HOOK_X86(pfn, n)
#else
#define DECLARE_T_HOOK(pfn, n) _DECLARE_T_HOOK(pfn)
#endif


#define T_HOOKS_BEGIN(name) T_HOOK_ENTRY name[] = {
#define T_HOOK(pfn) { &__imp_ ## pfn, hook_ ## pfn }
#define T_HOOKS_END() };

