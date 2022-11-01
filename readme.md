code in Payload<32|64>.dll search for

UNICODE_STRING LdrpKernel32DllName = RTL_CONSTANT_STRING(L"KERNEL32.DLL");

inside ntdll, and if found - in new created process overwrite KERNEL32.DLL to own "bootstrap" dll name ( LdrpKernel<32|64>.dll )
as result LdrpKernel<32|64>.dll loaded to new process. currently it mast export 2 api:
BaseThreadInitThunk and TermsrvGetWindowsDirectoryW

EXTERN_C
WINBASEAPI
NTSTATUS
FASTCALL
BaseThreadInitThunk(BOOL bInitializeTermsrv, 
	LPTHREAD_START_ROUTINE lpStartAddress, 
	PVOID lpParameter
	);


BaseThreadInitThunk with bInitializeTermsrv = true called just before loader begin initialize static linked dlls from exe
we can here load Payload<32|64>.dll and initiaize it
as result code of Payload<32|64>.dll will be called not only before exe entry point (for this enough inject apc in first thread of new process)
but and before tls initializers and other dlls. sense only in early control.
inject work for all 4 cases ( 32-> 32, 32->64, 64->64, 64->32)
for 32->64 case need execute 64 bit code in wow process ( 64IN32 project)

test<64|32>.bat for test

Payload<32|64>.dll loaded to regsvr32.exe and started cmd.exe with inject
Payload<32|64>.dll hook CreateProcessInternalW for do inject to new created processes (if any)