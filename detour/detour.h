#pragma once

struct T_HOOK_ENTRY 
{
	PCSTR funcName;
	PVOID hook;
	void** pThunk;
	union Z_DETOUR_TRAMPOLINE* pTramp;
};

struct TR_HOOK_DLL 
{
	PCWSTR lpcszDllName;
	T_HOOK_ENTRY hookV[];
};

#define _DECLARE_TR_HOOK(pfn) extern "C" { extern PVOID __imp_##pfn; }
#define DECLARE_TR_HOOK_X86(pfn, n) _DECLARE_TR_HOOK(pfn) __pragma(comment(linker, _CRT_STRINGIZE(/alternatename:___imp_##pfn##=__imp__##pfn##@##n)))

#ifdef _M_IX86
#define DECLARE_TR_HOOK(pfn, n) DECLARE_TR_HOOK_X86(pfn, n)
#else
#define DECLARE_TR_HOOK(pfn, n) _DECLARE_TR_HOOK(pfn)
#endif

#define TR_DLL_NAME(dllname) tr_##dllname
#define HOOK_NAME(pfn) hook_##pfn

#define BEGIN_TR_HOOK(dllname) TR_HOOK_DLL TR_DLL_NAME(dllname) = { L ## #dllname L".dll", {
#define BEGIN_TR_HOOK2(dllname, name) TR_HOOK_DLL TR_DLL_NAME(dllname) = { _CRT_WIDE(name), {
#define TR_HOOK_ENTRY(pfn) { #pfn, HOOK_NAME(pfn), (void**)&__imp_##pfn },
#define TR_HOOK_ENTRY_ORD(i, pfn) { (PCSTR)(i), HOOK_NAME(pfn), (void**)&__imp_##pfn },
#define END_TR_HOOK() {}}};

#define BEGIN_TR_DLLs(x) TR_HOOK_DLL* x[] = {
#define TR_DLL(dllname) &TR_DLL_NAME(dllname),
#define END_TR_DLLs() 0 };

NTSTATUS NTAPI TrInit(PVOID ImageBase = &__ImageBase);
void NTAPI TrHook(TR_HOOK_DLL* pphDLL[]);
void NTAPI TrHook(PCUNICODE_STRING DllName, TR_HOOK_DLL* pphDLL[]);// hmod = LdrGetDllHandle(DllName)
void NTAPI TrHook(PVOID hmod, PCUNICODE_STRING DllName, TR_HOOK_DLL* pphDLL[]);// if we already have hmod
void NTAPI TrUnHook(TR_HOOK_DLL* pphDLL[]);
NTSTATUS NTAPI TrHook(PVOID pv, T_HOOK_ENTRY* entry, _In_opt_ BOOLEAN bProtect = TRUE);// pv address for hook
NTSTATUS NTAPI TrUnHook(T_HOOK_ENTRY* entry);
