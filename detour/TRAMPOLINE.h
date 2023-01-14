#pragma once

union Z_DETOUR_TRAMPOLINE 
{
	Z_DETOUR_TRAMPOLINE* Next;

	struct 
	{
		union {
			ULONG ff250000;
			struct {
				USHORT cbRestore;      // size of original target code.
				USHORT ff25;		   // jmp [pvDetour]
			};
		};
		ULONG  disp;
		PVOID  pvDetour;       // first instruction of detour function.
		PVOID  pvJmp;
		PVOID  pvRemain;       // first instruction after moved code.
		BYTE   rbCode[32];     // target code + jmp [pvRemain]
		BYTE   rbRestore[8];   // original target code.
	};

	~Z_DETOUR_TRAMPOLINE(){}

	Z_DETOUR_TRAMPOLINE(PVOID pvDetour) : pvDetour(pvDetour)
	{
		ff250000 = 0x25ff0000;
#if defined(_M_X64)  
		disp = 0;
#elif defined (_M_IX86)
		disp = (ULONG_PTR)&pvDetour;
#else
#error ##
#endif
		RtlFillMemoryUlong(rbCode, sizeof(rbCode), 0xcccccccc);
	}

	void* operator new(size_t, void* pvTarget);

	void operator delete(PVOID pv);

	PVOID Init(PVOID pvTarget);

	NTSTATUS Set();

	NTSTATUS Remove();
};
