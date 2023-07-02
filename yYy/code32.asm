.686

.MODEL FLAT

.code

?FindLdrpKernel3264DllName@NT@@YI_KPA_K@Z proc
	xor edx,edx
	mov eax,[esp]
	push eax
	push eax
	jmp ?InitBootstrapI64@NT@@YIJPAX0PB_WK@Z
?FindLdrpKernel3264DllName@NT@@YI_KPA_K@Z endp

?InitBootstrapI64@NT@@YIJPAX0PB_WK@Z proc
	xchg edi,[esp+4]
	xchg esi,[esp+8]
	jmp @2
	ALIGN 16
@3:
INCLUDE <../x64/release/64btr.asm>
@2:
	push 33h
	call @1
	;++++++++ x64 +++++++++
	call @3
	retf
	;-------- x64 ---------
@1:
	call fword ptr [esp]
	pop ecx
	pop ecx
	mov edi,[esp+4]
	mov esi,[esp+8]
	ret 8
?InitBootstrapI64@NT@@YIJPAX0PB_WK@Z endp

end