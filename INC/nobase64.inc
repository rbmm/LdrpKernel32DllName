
NtApi macro name, string
name proc
	lea rax,@@1
	jmp common_imp_call
@@1: 
	DB string,0
NtApi endp
endm

; void *__cdecl NT::GetFuncAddress(const char *)
extern ?GetFuncAddress@NT@@YAPEAXPEBD@Z : PROC

.code

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

?fmemcmp@NT@@YADPEBX0_K@Z proc
  mov rax,rsi
  mov rsi,rcx
  xchg rdi,rdx
  mov ecx,r8d
  repe cmpsb
  mov rsi,rax
  mov rdi,rdx
  mov al,0
  jz @@2
  js @@1
  inc al
@@2:
  ret
@@1:
  dec al
  ret
?fmemcmp@NT@@YADPEBX0_K@Z endp

