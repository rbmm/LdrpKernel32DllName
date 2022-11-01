include <../inc/nobase64.inc>

_TEXT segment

; void *__cdecl NT::FindLdrpKernel32DllName(unsigned __int64 *)
extern ?FindLdrpKernel32DllName@NT@@YAPEAXPEA_K@Z : PROC

; long __cdecl NT::InitBootstrapI(void *,void **,const wchar_t *,unsigned long)
extern ?InitBootstrapI@NT@@YAJPEAXPEAPEAXPEB_WK@Z : PROC

ep proc
	mov rax,gs:[10h]
	xchg rsp,rax
	push rax
	sub rsp,28h
	
	movsxd rcx,ecx
	movsxd rdx,edx
	movsxd r8,edi
	movsxd r9,esi
	
	test rdx,rdx
	jz @@0
	call ?InitBootstrapI@NT@@YAJPEAXPEAPEAXPEB_WK@Z
	jmp @@1
@@0:
	call ?FindLdrpKernel32DllName@NT@@YAPEAXPEA_K@Z
@@1:	
	mov rdx,rax
	shr rdx,32
	add rsp,28h
	pop rsp
	ret
ep endp

_HMOD ntdll, <>

createWstring ?wkernel32@NT@@YAPEB_WXZ, kernel32.dll

createFunc NtAllocateVirtualMemory
createFunc NtWriteVirtualMemory
createFunc NtProtectVirtualMemory
createFunc NtFreeVirtualMemory
createFunc RtlImageNtHeader
createFunc RtlEqualUnicodeString
createFunc RtlInitUnicodeString

_TEXT ends

end