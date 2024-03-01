
; void *__cdecl NT::FindLdrpKernel32DllName(unsigned __int64 *)
extern ?FindLdrpKernel32DllName@NT@@YAPEAXPEA_K@Z : PROC

; long __cdecl NT::InitBootstrapI(void *,void **,const wchar_t *,unsigned long)
extern ?InitBootstrapI@NT@@YAJPEAXPEAPEAXPEB_WK@Z : PROC

; void *__cdecl NT::GetFuncAddress(const char *)
extern ?GetFuncAddress@NT@@YAPEAXPEBD@Z : PROC

.code

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; must be first function in .text section !

ep proc
	mov rax,gs:[10h]
	xchg rsp,rax
	push rax
	sub rsp,28h
	
	mov ecx,ecx
	mov edx,edx
	mov r8d,edi
	mov r9d,esi
	
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

common_imp_call proc private
  push r9
  push r8
  push rdx
  push rcx
  sub rsp,28h
  mov rcx,rax
  call ?GetFuncAddress@NT@@YAPEAXPEBD@Z
  add rsp,28h
  pop rcx
  pop rdx
  pop r8
  pop r9
  jmp rax
common_imp_call endp

NtApi MACRO name
name proc
	lea rax,@@1
	jmp common_imp_call
@@1: 
	DB '&name',0
name endp
ENDM

NtApi NtAllocateVirtualMemory
NtApi NtWriteVirtualMemory
NtApi NtProtectVirtualMemory
NtApi NtFreeVirtualMemory
NtApi RtlImageNtHeader
NtApi RtlEqualUnicodeString
NtApi RtlInitUnicodeString

end